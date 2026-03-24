# Beacon

Beacon is a modular, passive-first attack surface scanner built for security engineers and developers who need actionable reconnaissance without false positives. It discovers subdomains, fingerprints technology stacks, checks email and TLS hygiene, probes for exposed files and cloud buckets, and — with explicit permission — runs active vulnerability payloads. Findings are enriched with AI-generated context and remediation guidance via the Claude API, and every scan is stored locally so you can track your attack surface over time.

## Table of Contents

- [Quick Start](#quick-start)
- [Docker](#docker)
- [Remote Mode (beacond)](#remote-mode-beacond)
- [CLI Reference](#cli-reference)
  - [beacon install](#beacon-install)
  - [beacon scan](#beacon-scan)
  - [beacon history](#beacon-history)
  - [beacon report](#beacon-report)
  - [beacon analyze](#beacon-analyze)
  - [beacon playbook](#beacon-playbook)
  - [beacon browse](#beacon-browse)
- [Configuration](#configuration)
  - [Config File](#config-file)
  - [Environment Variables](#environment-variables)
- [Scan Modes](#scan-modes)
- [Output Formats](#output-formats)
- [Scanners](#scanners)
- [Playbooks](#playbooks)
- [Modules](#modules)
- [External Tool Dependencies](#external-tool-dependencies)
- [Architecture Overview](#architecture-overview)

---

## Quick Start

**Requires Go 1.21+.**

```sh
# Install the beacon CLI
go install github.com/stormbane/beacon/cmd/beacon@latest

# Install required external tools (nuclei, subfinder, testssl.sh, etc.)
beacon install

# Run a surface scan against a domain you own or have permission to scan
beacon scan --domain example.com

# Surface scan with JSON output written to a file
beacon scan --domain example.com --format json --out report.json

# Deep scan (requires explicit permission acknowledgment)
beacon scan --domain example.com --deep --permission-confirmed
```

Results are saved to `~/.beacon/beacon.db` (SQLite). Run `beacon` with no arguments to open the interactive TUI browser for past scans.

---

## Docker

The published image bundles `nuclei`, `subfinder`, and `testssl.sh`. The `beacon.db` database and config file are expected at `/root/.beacon/`.

```sh
# Pull the image
docker pull ghcr.io/stormbane/beacon:latest

# Run a surface scan, mounting a local directory for persistence
docker run --rm \
  -v "$HOME/.beacon:/root/.beacon" \
  -e BEACON_ANTHROPIC_API_KEY="sk-ant-..." \
  ghcr.io/stormbane/beacon:latest \
  scan --domain example.com

# Produce an HTML report and copy it out
docker run --rm \
  -v "$HOME/.beacon:/root/.beacon" \
  -v "$(pwd)/reports:/reports" \
  ghcr.io/stormbane/beacon:latest \
  scan --domain example.com --format html --out /reports/example.html
```

To build locally from the repository:

```sh
docker build -f deploy/Dockerfile -t beacon .
```

---

## Remote Mode (beacond)

`beacond` is the Beacon daemon — a REST API server that accepts scan jobs and streams progress over Server-Sent Events. The `beacon` CLI can act as a remote client, delegating all scan work to a `beacond` instance rather than running locally.

**Start the server:**

```sh
go install github.com/stormbane/beacon/cmd/beacond@latest

BEACON_API_KEY="your-secret-key" \
BEACON_ANTHROPIC_API_KEY="sk-ant-..." \
BEACON_ADDR=":8080" \
BEACON_WORKERS="4" \
  beacond
```

**Connect the CLI to the server:**

```sh
# Via flags
beacon scan --domain example.com \
  --server https://beacon.example.com \
  --api-key your-secret-key

# Via environment variables (persistent across all commands)
export BEACON_SERVER_URL=https://beacon.example.com
export BEACON_SERVER_API_KEY=your-secret-key
beacon scan --domain example.com
```

You can also set `server.url` and `server.api_key` in `~/.beacon/config.yaml` (see [Configuration](#configuration)).

**Deploy to Fly.io** using the included `fly.toml`:

```sh
fly launch --no-deploy
fly secrets set BEACON_API_KEY=your-secret-key BEACON_ANTHROPIC_API_KEY=sk-ant-...
fly deploy
```

---

## CLI Reference

### beacon install

Checks whether all required external tools are available and installs any that are missing. Go-based tools are installed via `go install`. `testssl.sh` is downloaded from GitHub. `theHarvester` is installed via Homebrew (macOS) or apt (Debian/Ubuntu).

```
beacon install
```

No flags. Prints one status line per tool (`ok`, `skipped`, or `FAILED`).

---

### beacon scan

Runs a scan against a domain or a GitHub organisation.

```
beacon scan --domain <domain> [flags]
beacon scan --github <org-or-repo> [flags]
```

| Flag | Description |
|------|-------------|
| `--domain <domain>` | Target domain to scan. Required unless `--github` is provided. |
| `--github <org>` | Scan a GitHub organisation or `org/repo` for Actions workflow vulnerabilities. Mutually exclusive with `--domain`. |
| `--deep` | Enable active probing. Requires `--permission-confirmed`. |
| `--permission-confirmed` | Acknowledge that you have explicit written authorisation to run active probes against the target. |
| `--format <fmt>` | Output format: `text` (default), `html`, `json`, `markdown`. |
| `--out <path>` | Write the report to a file instead of stdout. |
| `--severity <level>` | Minimum severity to include in the report: `critical`, `high`, `medium`, `low`, `info` (default). Findings below this threshold are not enriched or sent to the Claude API. |
| `--verbose` | Print scanner-level progress to stderr: which scanner is running, fingerprint hits, skip reasons. |
| `--server <url>` | Route the scan to a remote `beacond` instance. Overrides `BEACON_SERVER_URL`. |
| `--api-key <key>` | Bearer token for the remote `beacond` instance. Overrides `BEACON_SERVER_API_KEY`. |
| `--cidr <cidr>` | Additional CIDR range(s) to include in port scanning. Can be repeated for multiple ranges. |

**Examples:**

```sh
beacon scan --domain example.com
beacon scan --domain example.com --format json --out report.json
beacon scan --domain example.com --severity high
beacon scan --domain example.com --deep --permission-confirmed
beacon scan --domain example.com --format html --out report.html
beacon scan --domain example.com --server https://beacon.internal --api-key sk-...
beacon scan --github myorg
beacon scan --github myorg/myrepo
```

---

### beacon history

Lists all past scans for a given domain in reverse chronological order.

```
beacon history --domain <domain>
```

| Flag | Description |
|------|-------------|
| `--domain <domain>` | Domain to list scan history for. Required. |

Output is a tab-formatted table with columns: `ID`, `DOMAIN`, `TYPE`, `STATUS`, `FINDINGS`, `STARTED`.

---

### beacon report

Re-renders a saved scan report from the local database.

```
beacon report --id <scan-id> [flags]
```

| Flag | Description |
|------|-------------|
| `--id <scan-id>` | Scan run ID to retrieve. Required. Use `beacon history --domain <domain>` to find IDs. |
| `--format <fmt>` | Output format: `text` (default), `html`, `json`, `markdown`. |
| `--out <path>` | Write the report to a file instead of stdout. |
| `--severity <level>` | Minimum severity to include: `critical`, `high`, `medium`, `low`, `info` (default). |

---

### beacon analyze

Runs a batch AI analysis across all completed scans, using Claude to review findings and generate playbook improvement suggestions. Suggestions are stored in the local database and can be reviewed with `beacon playbook suggestions`.

```
beacon analyze
```

Requires `BEACON_ANTHROPIC_API_KEY`. Reads completed scans from the local store and submits finding patterns to Claude, which proposes additions or improvements to playbook YAML. Each suggestion is stored with `status: pending` until actioned.

---

### beacon playbook

Manages AI-generated playbook suggestions produced by `beacon analyze`.

```
beacon playbook suggestions
beacon playbook open-pr --id <suggestion-id>
```

| Subcommand | Description |
|------------|-------------|
| `suggestions` | Lists pending playbook suggestions with their proposed YAML and target playbook name. |
| `open-pr --id <id>` | Opens a GitHub pull request adding or modifying the suggested playbook YAML. Requires `BEACON_GITHUB_TOKEN`. |

---

### beacon browse

Opens an interactive TUI browser for navigating past scans and their findings. Invoked automatically when `beacon` is run with no arguments.

```
beacon browse
```

Key bindings:
- `↑` / `↓` — navigate the scan list
- `Enter` — drill into findings for the selected scan
- `s` — stop a running scan
- `b` — detach from a running scan (the scan continues in the background; use `beacon browse` to return to it)
- `q` / `Esc` — quit

---

## Configuration

### Config File

Beacon reads `~/.beacon/config.yaml` on startup. The file is optional; all values have defaults or fall back to environment variables. Set `BEACON_CONFIG=/path/to/config.yaml` to use a custom path.

**Example `~/.beacon/config.yaml`:**

```yaml
# AI enrichment — without this key, findings are not individually enriched,
# no executive summary is generated, and beacon analyze/playbook are unavailable.
anthropic_api_key: "sk-ant-..."

# Optional API integrations — each unlocks additional passive data sources.
# Scans run without any of these; they extend coverage and context.
shodan_api_key: ""
otx_api_key: ""
hibp_api_key: ""
bing_api_key: ""
virustotal_api_key: ""
securitytrails_api_key: ""
censys_api_id: ""
censys_api_secret: ""
greynoise_api_key: ""

# GitHub personal access token — required for beacon playbook open-pr
# and increases GitHub API rate limits for --github scans.
github_token: ""

# Claude model used for AI enrichment (default: claude-sonnet-4-6).
# Options: claude-opus-4-6 (higher quality), claude-haiku-4-5-20251001 (fastest/cheapest)
claude_model: "claude-sonnet-4-6"

# External tool binary paths — only needed if the binary is not on PATH.
nmap_bin: "nmap"
nuclei_bin: "nuclei"
gitleaks_bin: "gitleaks"
testssl_bin: "testssl.sh"
amass_bin: "amass"
gau_bin: "gau"
katana_bin: "katana"
gowitness_bin: "gowitness"
httpx_bin: "httpx"
dnsx_bin: "dnsx"
ffuf_bin: "ffuf"

# SQLite database location. Defaults to ~/.beacon/beacon.db.
store:
  path: "~/.beacon/beacon.db"

# Remote beacond server — when set, beacon CLI acts as a client.
server:
  url: ""
  api_key: ""

# SMTP settings for email delivery of scan reports.
smtp:
  host: ""
  port: 587
  user: ""
  pass: ""
  from: ""
```

### Environment Variables

All `BEACON_*` environment variables override the corresponding config file value. CLI flags (where available) take the highest precedence.

#### API Keys

| Variable | Config key | Description |
|----------|-----------|-------------|
| `BEACON_ANTHROPIC_API_KEY` | `anthropic_api_key` | Enables Claude AI enrichment: per-finding remediation guidance, severity context, false-positive assessment, executive summary generation, and the `beacon analyze` / `beacon playbook` workflows. |
| `BEACON_SHODAN_API_KEY` | `shodan_api_key` | Enables Shodan host lookups for each discovered IP address. Free tier: 1 result per IP, no active scanning. Register at [shodan.io](https://shodan.io). |
| `BEACON_OTX_API_KEY` | `otx_api_key` | Enables AlienVault OTX passive DNS subdomain discovery. Free registration at [otx.alienvault.com](https://otx.alienvault.com). |
| `BEACON_HIBP_API_KEY` | `hibp_api_key` | Enables Have I Been Pwned domain breach lookup. Requires a paid API key from [haveibeenpwned.com](https://haveibeenpwned.com/API/Key). |
| `BEACON_BING_API_KEY` | `bing_api_key` | Enables Bing Search API dorking for indexed sensitive files and exposed admin panels. Free tier: 1,000 queries/month via Azure Cognitive Services. |
| `BEACON_VIRUSTOTAL_API_KEY` | `virustotal_api_key` | Enables domain reputation and malware association lookups. Free tier: 500 requests/day at [virustotal.com](https://virustotal.com). |
| `BEACON_SECURITYTRAILS_API_KEY` | `securitytrails_api_key` | Enables historical DNS records and enhanced subdomain enumeration. Register at [securitytrails.com](https://securitytrails.com). |
| `BEACON_CENSYS_API_ID` | `censys_api_id` | Censys API ID for internet-wide host and certificate data. Free tier: 250 queries/month at [censys.io](https://censys.io). |
| `BEACON_CENSYS_API_SECRET` | `censys_api_secret` | Censys API secret — used together with `BEACON_CENSYS_API_ID`. |
| `BEACON_GREYNOISE_API_KEY` | `greynoise_api_key` | Enriches discovered IPs with GreyNoise noise context (is this IP a known scanner?). Free community key at [greynoise.io](https://greynoise.io). |
| `BEACON_GITHUB_TOKEN` | `github_token` | GitHub personal access token. Raises the GitHub API rate limit from 60 to 5,000 req/hour, enables scanning private repositories, and is required for `beacon playbook open-pr`. |

#### Model Selection

| Variable | Config key | Description |
|----------|-----------|-------------|
| `BEACON_CLAUDE_MODEL` | `claude_model` | Overrides the Claude model used for AI enrichment and summary generation. Default: `claude-sonnet-4-6`. |

#### Storage and Config Path

| Variable | Config key | Description |
|----------|-----------|-------------|
| `BEACON_STORE_PATH` | `store.path` | Path to the SQLite database file. Default: `~/.beacon/beacon.db`. |
| `BEACON_CONFIG` | _(path only)_ | Full path to the config YAML file. Default: `~/.beacon/config.yaml`. Useful for running Beacon under a service account or in containers. |

#### Remote Server (beacond client)

| Variable | Config key | Description |
|----------|-----------|-------------|
| `BEACON_SERVER_URL` | `server.url` | URL of a remote `beacond` instance. When set, all `beacon scan` commands are delegated to that server rather than running locally. |
| `BEACON_SERVER_API_KEY` | `server.api_key` | Bearer token for authenticating to the remote `beacond` instance. |

#### beacond Server Configuration

These variables are consumed by `beacond` only, not by the `beacon` CLI.

| Variable | Default | Description |
|----------|---------|-------------|
| `BEACON_ADDR` | `:8080` | TCP listen address for the `beacond` HTTP server. |
| `BEACON_WORKERS` | `2` | Number of concurrent scan jobs `beacond` will process simultaneously. |
| `BEACON_API_KEY` | _(none)_ | Bearer token required in `Authorization: Bearer <token>` on all requests. If unset, the API is open to anyone — not recommended for production. |

#### SMTP

| Variable | Config key | Description |
|----------|-----------|-------------|
| `BEACON_SMTP_HOST` | `smtp.host` | SMTP server hostname for email delivery of scan reports. |
| `BEACON_SMTP_PORT` | `smtp.port` | SMTP port. Default: `587`. |
| `BEACON_SMTP_USER` | `smtp.user` | SMTP username. |
| `BEACON_SMTP_PASS` | `smtp.pass` | SMTP password. |
| `BEACON_SMTP_FROM` | `smtp.from` | Sender address used in outbound report emails. |

#### Binary Path Overrides

Set these when the tool binary is not on `PATH` or you want to pin a specific version.

| Variable | Config key | Default binary name |
|----------|-----------|---------------------|
| `BEACON_NMAP_BIN` | `nmap_bin` | `nmap` |
| `BEACON_NUCLEI_BIN` | `nuclei_bin` | `nuclei` |
| `BEACON_GITLEAKS_BIN` | `gitleaks_bin` | `gitleaks` |
| `BEACON_TESTSSL_BIN` | `testssl_bin` | `testssl.sh` |
| `BEACON_AMASS_BIN` | `amass_bin` | `amass` |
| `BEACON_GAU_BIN` | `gau_bin` | `gau` |
| `BEACON_KATANA_BIN` | `katana_bin` | `katana` |
| `BEACON_GOWITNESS_BIN` | `gowitness_bin` | `gowitness` |
| `BEACON_HTTPX_BIN` | `httpx_bin` | `httpx` |
| `BEACON_DNSX_BIN` | `dnsx_bin` | `dnsx` |
| `BEACON_FFUF_BIN` | `ffuf_bin` | `ffuf` |

---

## Scan Modes

### Surface (default)

Surface mode is entirely passive. It uses only:

- Public DNS queries (A, AAAA, MX, TXT, NS, CNAME, DNSKEY)
- Standard HTTPS/TLS handshakes and certificate inspection
- Reading publicly accessible HTTP responses — no authentication, no payloads, no login attempts
- Third-party passive data sources: crt.sh, Shodan, AlienVault OTX, SecurityTrails, VirusTotal, Censys, urlscan.io, Wayback Machine

Surface mode is safe to run against any domain at any time. The only network traffic it generates is equivalent to what a browser, a search engine crawler, or a public DNS resolver would produce.

### Deep

Deep mode adds active probing that sends payloads and crafted requests to the target system:

- Vulnerability payload probes: XSS, SQL injection, SSRF, path traversal, SSTI, CRLF injection
- Credential and default-login attempts via Nuclei templates
- Aggressive TLS cipher and protocol negotiation via testssl.sh
- Crafted HTTP headers: Host header injection, WAF bypass headers (X-Forwarded-For, X-Real-IP)
- WebSocket origin forgery probes (CSWSH)
- Active LLM prompt injection against detected AI endpoints
- Virtual host enumeration via crafted Host headers
- Directory and path busting with technology-specific wordlists

**Deep mode requires `--deep --permission-confirmed` together.** By passing `--permission-confirmed` you confirm that:

1. You have explicit written authorisation from the owner of the target to perform active security testing.
2. You understand that performing active probes without authorisation constitutes unauthorised computer access under applicable law.
3. You accept full legal responsibility for your use of deep mode.

Applicable statutes include: US Computer Fraud and Abuse Act (18 U.S.C. § 1030), UK Computer Misuse Act 1990, EU Directive 2013/40/EU, German StGB §202a/§202c, Australian Criminal Code Act 1995 Part 10.7, Canadian Criminal Code s342.1, Japanese Unauthorized Computer Access Law, and equivalent legislation in other jurisdictions.

Beacon will refuse to run deep mode without `--permission-confirmed` and will print the full legal notice. This requirement cannot be bypassed.

---

## Output Formats

Specify the format with `--format`. The default is `text`. Use `--out <path>` to write to a file instead of stdout.

| Format | Description |
|--------|-------------|
| `text` | Terminal-friendly plain-text report. Suitable for piping, grepping, and reading in a terminal. Severity levels are shown with ASCII prefixes. |
| `markdown` | Markdown document with a severity summary table, asset inventory table (asset, detected tech stack, finding counts by severity), Mermaid network topology diagram, and per-finding detail blocks with evidence and remediation notes. |
| `html` | Self-contained HTML report with inline styles. No external dependencies — open directly in a browser or attach to a ticket. Includes the same content as the Markdown format with richer layout. |
| `json` | Structured JSON array of enriched findings. Each object includes the finding title, description, severity, asset, scanner, check ID, evidence map, remediation text, and CVSS metadata. Suitable for importing into SIEM tools, Jira, or custom dashboards. |

The HTML report is always saved to the local SQLite database regardless of the requested output format, so any past scan can be retrieved as any format at any time with `beacon report --id <id> --format <fmt>`.

---

## Scanners

Scanners are the atomic units of detection. Every scanner implements the `scanner.Scanner` interface (`Name() string` and `Run(ctx, asset, scanType) ([]Finding, error)`) and returns zero or more findings. Scanners have no knowledge of the database, playbooks, or pricing tiers — they receive a hostname and return findings.

Scanners run concurrently within the surface module, gated by per-asset run plans generated from matched playbooks. The module tracks skip reasons (no HTTP service, behind CDN without known origin IP, tool not installed, etc.) and records them in the store for debugging.

| Scanner | Mode | Description |
|---------|------|-------------|
| `email` | Surface | Checks SPF (missing, `+all`, overly permissive mechanisms), DKIM (probes common selectors), DMARC (`p=none`, missing reporting addresses), and MTA-STS policy via passive DNS and HTTPS lookups. No mail is sent. |
| `tls` | Surface | Native Go TLS handshake analysis: certificate expiry, weak RSA/EC key size, hostname mismatch, missing HSTS header, HSTS `max-age` below 1 year, missing `includeSubDomains`, OCSP revocation, forward secrecy (ECDHE cipher preference). |
| `dns` | Surface | DNSSEC presence check (missing DNSKEY record), wildcard DNS detection via random subdomain resolution. Both checks use only standard DNS lookups. |
| `portscan` | Surface | Pure-Go TCP connect scanner against a curated set of high-risk ports. Reads service banners and attempts unauthenticated access probes against Redis, Elasticsearch, MongoDB, CouchDB, Memcached, Cassandra, etcd, and other commonly exposed services. |
| `wafdetect` | Surface+Deep | Fingerprints WAF and CDN vendors from HTTP response headers and DNS patterns. In deep mode, additionally probes for origin IP exposure, Cloudflare Flexible SSL misconfiguration (origin served over plain HTTP), and IP-header bypass (X-Forwarded-For trusting). |
| `nuclei` | Surface+Deep | Wraps the Nuclei CLI as a subprocess. Surface tags: `ssl`, `dns`, `http-headers`, `exposure`, `misconfiguration`, `takeovers`, `technologies`. Deep tags add: `cves`, `network`, `injection`, `default-logins`. Matched playbooks contribute additional technology-specific tags. `dos`, `crash`, and `destructive` tags are always excluded. |
| `subdomain` | Surface | Combines crt.sh certificate transparency logs, urlscan.io, AlienVault OTX (with API key), SecurityTrails (with API key), and brute-force DNS resolution of ~160 curated common prefixes to enumerate all subdomains. |
| `cloudbuckets` | Surface | Probes AWS S3, Google Cloud Storage, and Azure Blob Storage for publicly accessible buckets using naming patterns derived from the target domain. Detection is via DNS and HTTP — no cloud credentials required. |
| `takeover` | Surface | Detects subdomain takeover vulnerabilities by resolving CNAME chains against known claimable platform suffixes (GitHub Pages, S3, Heroku, Netlify, Fastly, Azure, and ~40 others) and matching HTTP response bodies against platform-specific "unclaimed resource" fingerprints. |
| `whois` | Surface | Retrieves domain registration data: registrar, creation date, expiry date. Flags domains expiring within 30 days. |
| `harvester` | Surface | Runs theHarvester for additional subdomain and email address discovery via public OSINT sources (Bing, crt.sh, DNS, Hunter, etc.). |
| `historicalurls` | Surface | Fetches URL history from the Wayback Machine (via gau) to discover previously exposed endpoints, sensitive paths, and forgotten API versions. |
| `crawler` | Surface | Crawls the target using katana to discover additional endpoints and inline JavaScript files for downstream DLP analysis. |
| `screenshot` | Surface | Takes screenshots of each discovered asset using gowitness. Screenshots are stored in the database and displayed in the TUI and HTML report. Used as input for Claude Vision-based DLP analysis. |
| `webcontent` | Surface | Fetches and analyses JavaScript bundles and HTML source for hardcoded API keys, credentials, internal endpoint references, and debug artefacts. |
| `dlp` | Surface | Detects sensitive data exposure via two methods: (1) regex patterns for API keys, credentials, and PII run against HTTP response bodies; (2) Claude Vision analysis of screenshots for sensitive data rendered by JavaScript applications. Also probes high-value config dump paths (`/actuator/env`, `/rails/info/properties`, `/debug/vars`) for leaked secrets. |
| `assetintel` | Surface | Enriches discovered IP addresses with Shodan host data (open ports, banners, CVEs) and GreyNoise noise context (is this IP a known internet scanner?). |
| `typosquat` | Surface | Enumerates common typosquatting mutations of the domain (homoglyphs, transpositions, character additions/deletions, TLD swaps) and checks DNS resolution and MX records for each variant. |
| `passivedns` | Surface | Collects additional passive DNS history from SecurityTrails and VirusTotal for subdomain discovery and infrastructure mapping. |
| `graphql` | Surface | Probes common GraphQL endpoint paths (`/graphql`, `/api/graphql`, `/v1/graphql`) and attempts schema introspection. |
| `apiversions` | Surface | Probes for active API version endpoints (`/api/v1/`, `/api/v2/`, `/v1/`, `/v2/`, `/v3/`). |
| `exposedfiles` | Surface | Probes a high-confidence set of sensitive file paths: `.env`, `.git/config`, `.git/HEAD`, `backup.zip`, `dump.sql`, `server-status`, `.aws/credentials`, and similar. |
| `clickjacking` | Surface | Checks `X-Frame-Options` and `Content-Security-Policy: frame-ancestors` response headers for missing or permissive framing controls. |
| `aidetect` | Surface | Passively detects LLM and AI API endpoint patterns in page source, response headers, and HTTP responses. No prompts are sent; this is discovery only. |
| `saml` | Surface | Discovers SAML and SSO endpoint paths via passive path probing. No authentication payloads. |
| `iam` | Surface | Discovers IAM-adjacent endpoints: SCIM provisioning, OAuth device flow (`/device/code`), OAuth token introspection, dynamic client registration, and IdP admin panels. |
| `web3detect` | Surface | Detects Web3 wallet library references (ethers.js, web3.js) and Ethereum JSON-RPC endpoint patterns in page source. |
| `log4shell` | Surface | Detects Java application signals — JSESSIONID cookies, Tomcat-specific response headers — that indicate potential Log4Shell (CVE-2021-44228) exposure surface. |
| `hibp` | Surface | Queries Have I Been Pwned for breaches associated with the target domain. Requires `BEACON_HIBP_API_KEY`. |
| `dorks` | Surface | Runs search engine dorking queries via the Bing API to find indexed sensitive files, exposed admin panels, and misconfigured resources. Requires `BEACON_BING_API_KEY`. |
| `bgp` | Surface | Collects BGP/ASN data for discovered IP addresses for infrastructure attribution. |
| `cms-plugins` | Surface | Enumerates installed WordPress, Drupal, Joomla, and other CMS plugin/theme versions and flags those with known CVEs. Activated by the `wordpress`, `drupal`, and `cms` playbooks. |
| `jenkins` | Surface | Probes Jenkins for unauthenticated access to the web UI and REST API, script console exposure (`/script`), and user enumeration via the people API. |
| `wafdetect` | Surface+Deep | See row above. |
| `cdnbypass` | Surface | Probes for origin IP exposure and direct-to-origin access paths when a CDN/WAF is detected. Activated only when WAF detection confirms a CDN is in use. |
| `testssl` | Deep | Wraps testssl.sh for comprehensive TLS analysis: deprecated protocol detection (SSLv2, SSLv3, TLS 1.0, TLS 1.1), weak cipher suite enumeration, BEAST, POODLE, ROBOT, Lucky13, FREAK, Logjam vulnerability checks, and certificate transparency log checks. |
| `smuggling` | Deep | Probes for HTTP/1.1 request smuggling via CL.TE (Content-Length / Transfer-Encoding) and TE.CL desynchronisation patterns against the target's HTTP stack. |
| `vhost` | Deep | Enumerates virtual hosts by sending crafted `Host` headers. When a CDN origin IP is known (discovered by `wafdetect`), probes the origin directly to avoid testing CDN shared edge infrastructure that may serve many tenants. Skipped when behind a CDN and no origin IP is known. |
| `cors` | Deep | Sends two CORS preflight requests per asset and inspects `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` for permissive configurations (`*` with credentials, reflecting arbitrary origins). |
| `hostheader` | Deep | Tests for Host header injection by sending forged `Host` values and observing whether they are reflected in redirects or responses. Also checks for header-based SSRF via `X-Forwarded-Host`. |
| `ratelimit` | Deep | Probes for absent or trivially bypassable rate limiting on login endpoints and API paths by sending bursts of requests and inspecting `Retry-After` and response code patterns. |
| `jwt` | Deep | Detects JWT usage in responses and cookies, then tests for `alg:none` acceptance, weak HMAC secret brute-force candidates, and RSA/HMAC key confusion (algorithm confusion attack). |
| `oauth` | Deep | Probes discovered OAuth 2.0 endpoints for open redirect in `redirect_uri`, implicit flow token leakage, and PKCE bypass misconfigurations. |
| `autoprobe` | Deep | Username enumeration via HTTP response timing differentials and error message variation on login forms. Lockout policy detection via repeated synthetic-account requests. No real user credentials are ever used or attempted. |
| `websocket` | Deep | Probes WebSocket endpoints with forged `Origin` headers to detect Cross-Site WebSocket Hijacking (CSWSH) vulnerabilities. |
| `aillm` | Deep | Active prompt injection and system prompt extraction probes against detected LLM/AI API endpoints. Crafted payloads — deep mode only, requires `--permission-confirmed`. |
| `ssti` | Deep | Server-Side Template Injection probes for Jinja2, FreeMarker, ERB, Pebble, and Spring Expression Language. Uses mathematical expression payloads to detect evaluation without triggering OS command execution. |
| `crlf` | Deep | CRLF injection and HTTP response splitting probes injected via redirect parameters, `Location` headers, and query strings. Active payloads. |
| `dirbust` | Deep | Iterates URL paths from the playbook `dictionary` lists using ffuf (or a built-in fallback) with technology-appropriate wordlists. Only runs the paths contributed by matched playbooks, keeping request counts proportional to confirmed technology. |
| `saml` | Surface | SAML/SSO endpoint discovery via passive path probing. See surface row above. |
| `ghactions` | Surface | GitHub Actions workflow YAML static analysis for security misconfigurations: `pull_request_target` with untrusted input, hardcoded secrets, write permissions on public workflows, unpinned third-party actions, and script injection via `${{ github.event.* }}` expressions. Used exclusively by the `github` module. |

---

## Playbooks

Playbooks are YAML files embedded in the binary at build time from `internal/playbook/playbooks/`. They encode the security knowledge that drives what Beacon checks on each discovered asset.

**Playbook structure:**

```yaml
name: wordpress
description: >
  Human-readable description of what this technology is and why it matters
  from a security perspective.

match:
  any:
    - body_contains: "wp-content"
    - path_responds: "/wp-login.php"
    - header_value:
        name: "link"
        contains: "wp-json"

surface:
  scanners:
    - cms-plugins
  nuclei_tags:
    - wordpress
    - cms

deep:
  scanners:
    - dirbust
  nuclei_tags:
    - wordpress
    - cves
  dictionary:
    - /wp-login.php
    - /wp-config.php
    - /xmlrpc.php
    - /wp-json/wp/v2/users

discovery:
  - type: probe_subdomains
    patterns:
      - "blog.{domain}"
      - "wp.{domain}"
```

**Match conditions** are evaluated per-asset after the initial HTTP fingerprinting phase:
- `always: true` — matches every asset (used by the `baseline` playbook)
- `body_contains` — substring match in the HTTP response body
- `path_responds` — the path returns a non-404 response
- `header_value` — named response header contains a value

The `baseline` playbook is always the first playbook applied and runs on every asset regardless of technology. All other playbooks activate only when their match conditions are satisfied for a specific asset, so technology-specific checks only run where confirmed.

**Currently bundled playbooks** (90+):

Web frameworks and CMS: WordPress, Drupal, Ghost, CraftCMS, Laravel, Rails, Django, Next.js, Spring Boot, Strapi, Langflow, n8n, Hasura, Airflow

Security and infrastructure: Cloudflare, CloudFront, Akamai, Fastly, Netlify, Vercel, Render, Fly.io, GitHub Pages, GitLab, Vault, Keycloak, Active Directory / SAML

Databases and analytics: Elasticsearch, OpenSearch, Kibana, Grafana, Prometheus, Splunk, InfluxDB, Cassandra, Kafka, Redis Insight, pgAdmin, phpMyAdmin, Adminer, Zabbix

Network and edge appliances: Cisco ASA, Cisco FMC, Palo Alto PAN-OS, Fortinet FortiGate, FortiWeb, F5 BIG-IP, Citrix NetScaler, Ivanti Connect Secure, Ivanti EPM/EPMM, Check Point, SonicWall, HP Aruba, HPE OneView, MikroTik, Ubiquiti, Envoy admin

Cloud: AWS EC2, AWS S3, Azure App Service, Azure Blob, GCP Compute, GCP Storage

Operational tools: Jenkins, Jupyter, Kubernetes Dashboard, Portainer, Traefik, Grafana (proxy variant), Wazuh, SolarWinds WHD, BeyondTrust, Veeam, SAP NetWeaver, Weblogic, Apache Tomcat

IoT and specialised: IP cameras, MQTT brokers, Modbus/SCADA, Web3/MCP servers, AI/LLM endpoints

---

## Modules

Modules are higher-level orchestration units that group related scanners and manage execution context. The `module.Module` interface requires `Name()`, `Tier()`, `RequiredInputs()`, and `Run(ctx, input, scanType)`.

| Module | Tier | Input type | Description |
|--------|------|-----------|-------------|
| `surface` | Free | `domain` | The primary domain-scanning module. Enumerates subdomains, fingerprints each asset, builds a playbook-driven run plan, then executes all applicable scanners concurrently. Manages WAF/CDN detection, origin IP discovery, scanner skip logic, and scan metrics collection. |
| `github` | Basic | `github` | Scans GitHub organisation repositories for Actions workflow security misconfigurations using static analysis rules applied to fetched YAML workflow files. |
| `iac` | Pro | `iac` | Infrastructure-as-Code scanning via trivy for Terraform and Kubernetes manifests. _(Phase 2 — stub implementation)_ |
| `cloud` | Premium | `cloud` | Cloud security posture scanning for AWS, GCP, and Azure via prowler. _(Phase 3 — stub implementation)_ |
| `kubernetes` | Premium | `kubernetes` | Kubernetes cluster misconfiguration and RBAC scanning. _(Phase 3 — stub implementation)_ |

---

## External Tool Dependencies

`beacon install` handles installation of the tools listed below. Binary paths can be overridden per tool via config file or environment variable.

| Tool | Install method | Required for |
|------|---------------|-------------|
| `nuclei` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | Vulnerability and misconfiguration template scanning (surface + deep) |
| `subfinder` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Passive subdomain enumeration from public sources |
| `amass` | `go install github.com/owasp-amass/amass/v4/...@master` | Additional subdomain enumeration and DNS brute-forcing |
| `gau` | `go install github.com/lc/gau/v2/cmd/gau@latest` | Historical URL collection from Wayback Machine, OTX, urlscan |
| `katana` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | Web crawling and JavaScript endpoint discovery |
| `gowitness` | `go install github.com/sensepost/gowitness@latest` | Screenshots of discovered assets |
| `testssl.sh` | Downloaded from GitHub (curl) — not available on Windows | Deep TLS cipher suite and vulnerability analysis |
| `theHarvester` | Homebrew (`brew install theharvester`) / apt (`apt install theharvester`) | Email and subdomain OSINT harvesting |
| `httpx` | `go install` (optional) | Faster alive-checking and HTTP probing for discovered hosts |
| `dnsx` | `go install` (optional) | Faster batch DNS resolution for subdomain lists |
| `ffuf` | `go install` (optional) | Faster directory and path busting with WAF evasion support |
| `nmap` | System package manager (optional) | Network port scanning — Beacon falls back to its pure-Go scanner when absent |

Tools marked optional improve performance or coverage but are not required for a functional scan. When a tool is absent, Beacon either uses a built-in fallback or skips that specific check and records the skip reason.

---

## Architecture Overview

```
beacon CLI (cmd/beacon)
  |
  +-- Config (internal/config)
  |     YAML file + BEACON_* environment variable overrides
  |
  +-- Store (internal/store/sqlite)
  |     SQLite: targets, scan runs, findings, enriched findings,
  |     reports, asset executions, scan metrics, playbook suggestions
  |
  +-- Module (internal/module)
  |   |
  |   +-- surface (internal/modules/surface)
  |   |     Subdomain enumeration -> per-asset HTTP fingerprinting
  |   |     -> playbook matching -> RunPlan construction
  |   |     -> concurrent scanner execution -> findings collection
  |   |
  |   +-- github (internal/modules/github)
  |   |     GitHub API -> workflow YAML -> static analysis rules
  |   |
  |   +-- iac    (internal/modules/iac)      [Phase 2]
  |   +-- cloud  (internal/modules/cloud)    [Phase 3]
  |   +-- k8s    (internal/modules/kubernetes) [Phase 3]
  |
  +-- Scanners (internal/scanner/*)
  |     50+ atomic detectors, each implementing scanner.Scanner
  |     Name() string
  |     Run(ctx, asset, scanType) ([]Finding, error)
  |
  +-- Playbooks (internal/playbook)
  |     Registry: loads ~90 embedded YAML playbooks at startup
  |     Match engine: evaluates conditions per asset fingerprint
  |     RunPlan builder: unions and deduplicates scanner/tag/path lists
  |
  +-- Enrichment (internal/enrichment)
  |     Claude enricher: per-finding remediation + false-positive context
  |     ContextualizeAndSummarize: executive summary across all findings
  |
  +-- Report (internal/report)
  |     text.go      plain-text renderer
  |     markdown.go  Markdown with asset inventory + Mermaid topology
  |     html         self-contained HTML renderer
  |     json.go      structured JSON renderer
  |
  +-- Analyze (internal/analyze)
        Batch AI analysis: submits finding patterns to Claude,
        parses returned playbook suggestions, stores for review

beacond (cmd/beacond)
  +-- API server (internal/api)
  |     REST endpoints: POST /scans, GET /scans/:id/stream (SSE),
  |     GET /scans/:id/report, middleware: bearer auth, rate limiting
  |
  +-- Worker pool (internal/worker)
        Bounded concurrency queue for scan jobs
        Each worker runs a full surface.Module.Run() pipeline
```

**Data flow for a `beacon scan --domain example.com` call:**

1. Config is loaded from `~/.beacon/config.yaml` and `BEACON_*` environment variables.
2. SQLite store is opened (created if absent). A `Target` and `ScanRun` record are created.
3. Missing API key warnings are printed for integrations that would improve coverage.
4. The `surface` module loads all playbooks from the embedded registry.
5. Subdomain enumeration runs (crt.sh, OTX, SecurityTrails, brute-force DNS) to produce the asset list.
6. Each asset undergoes initial HTTP fingerprinting: status, response headers, body excerpt, and a small set of path probes.
7. The playbook engine evaluates match conditions against each asset's fingerprint. The `baseline` playbook always matches; technology-specific playbooks match where their conditions hold.
8. Matched playbooks are unioned into a `RunPlan`: a deduplicated list of scanners, Nuclei tag selectors, and directory-bust paths.
9. All scanners in the `RunPlan` execute concurrently against the asset. The WAF detection result gates certain scanners (e.g., `vhost` is skipped behind a CDN without a known origin IP).
10. Findings from all scanners across all assets are collected and written to the store.
11. If `BEACON_ANTHROPIC_API_KEY` is set: findings above the severity threshold are sent to Claude individually for remediation context, severity justification, and false-positive assessment. Claude then generates an executive summary across the full finding set.
12. Enriched findings and the summary are saved to the store. The scan run is marked completed.
13. The report is rendered in the requested format and written to stdout (or `--out <path>`).
