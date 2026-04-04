# Deferred Scanner Tests

These scanners require real application behavior that cannot be simulated with
static nginx configurations. They are tagged with the infrastructure needed.

## Requires Real Application Logic (Docker, but with actual vulnerable code)

### redos — `docker:vulnerable-app`
**Check ID:** `web.redos`
**Why deferred:** ReDoS detection requires a server that actually validates input
with a vulnerable regex. The scanner measures response time — a benign input must
respond in <1s while an evil input (30 a's + !) triggers >5s of catastrophic
backtracking. nginx cannot simulate regex processing delays.
**Test approach:** Build a minimal Go/Python container with a vulnerable regex on
the `?q=` parameter. Or find an existing vulnerable image.

### protopollution — `docker:nodejs-app`
**Check ID:** `web.prototype_pollution`
**Why deferred:** Prototype pollution requires a real Node.js Express app that
persists `__proto__` properties across POST→GET. nginx cannot simulate JavaScript
prototype chain behavior.
**Test approach:** Minimal Express app that does `Object.assign(state, req.body)`
and returns state on GET. Or use a known-vulnerable npm package.

### elinjection — `docker:java-app`
**Check ID:** `web.spel_injection`, `web.ognl_injection`, `web.el_injection`
**Why deferred:** Expression Language injection requires a Java app that actually
evaluates SpEL/OGNL/EL expressions from request parameters. The scanner injects
`${7*7}` and checks for `49` in the response — a static nginx return won't produce
the differential (more occurrences of `49` than baseline) the scanner requires.
**Test approach:** Spring Boot app with SpEL evaluation vulnerability, or
Apache Struts with OGNL injection.

### smuggling — `docker:proxy+backend`
**Check ID:** `web.http_request_smuggling`
**Why deferred:** HTTP request smuggling requires a genuine proxy/backend pair where
Content-Length vs Transfer-Encoding handling differs. The existing nginx+httpbin test
already sets up this topology but timing-based detection is inherently probabilistic.
**Status:** Existing test is acceptable as soft (`min_findings: 0`). The topology is
correct; whether it fires depends on the specific nginx+httpbin version combination.

### xsd-injection — `docker:xml-parser`
**Check ID:** `web.xsd_injection`
**Why deferred:** XSD injection requires a real XML parser that attempts to
fetch remote XSD schemas referenced in submitted XML. The scanner uses
timing-based detection — if the server tries to fetch the schema, response
takes >2s longer. nginx cannot simulate XML schema validation.
**Test approach:** Java app with JAXB/SAX parser or Python lxml app with
schema validation enabled. BaseX (`basex/basexhttp`) is one option.

## Requires Network Infrastructure

### portscan (extended) — `docker:multi-service`
**Partial coverage:** The `portscan-services.yaml` test covers Redis and FTP.
Additional services that would improve coverage:
- **Elasticsearch** (`docker:elasticsearch`) — port 9200, unauthenticated
- **MongoDB** (`docker:mongo`) — port 27017, unauthenticated
- **PostgreSQL** (`docker:postgres`) — port 5432
- **Prometheus** (`docker:prom/prometheus`) — port 9090

## Requires Cloud Infrastructure (deferred to later phase)

### Cloud posture scanners — `aws`, `gcp`, `azure`
- `internal/scanner/cloud/aws/ec2.go` — requires AWS credentials + EC2 instances
- `internal/scanner/cloud/aws/s3.go` — requires S3 buckets with specific policies
- `internal/scanner/cloud/gcp/compute.go` — requires GCP project
- `internal/scanner/cloud/azure/storage.go` — requires Azure subscription

### DNS-dependent scanners — `dns`
- `subdomain/passive.go` — requires real domain with DNS records
- `takeover/scanner.go` — requires dangling CNAME records
- `passivedns` — requires public DNS history APIs

### External service scanners — `internet`
- `ghactions/scanner.go` — requires GitHub repository access
- `ghrepo/scanner.go` — requires GitHub API access
- `bgp/scanner.go` — requires BGP/ASN lookup APIs
- `shodan` — requires Shodan API key

### WiFi scanner — `hardware:wifi-adapter`
- Requires wireless network adapter in monitor mode

### Email scanners — `dns` + `smtp`
- SPF, DMARC, DKIM — requires real domain with DNS records
- SMTP relay — requires actual SMTP server
