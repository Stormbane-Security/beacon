# CVE Tests That Cannot Run in Standard Drydock

These CVEs require infrastructure that exceeds standard drydock test constraints.
Each entry documents the CVE, why it cannot be tested, and what would be needed.

## CVE-2017-12635 — CouchDB Privilege Escalation (Admin Creation)
- **Check ID:** `cve.couchdb_priv_escalation`
- **Image:** `couchdb:2.1.0`
- **Why untestable:** All CouchDB 2.x images before 2.1.1 are x86-only and
  not available on ARM64 (Apple Silicon). The `couchdb:2.1.0` tag has been
  removed from Docker Hub entirely.
- **What would be needed:** An x86 CI runner, or a custom CouchDB 2.0.x build.

## CVE-2012-2122 — MySQL memcmp Timing Auth Bypass
- **Check ID:** `cve.mysql_auth_bypass_2012`
- **Image:** `mysql:5.5`
- **Why untestable:** The `mysql:5.5` image is x86-only. MySQL 5.5 and 5.6
  images do not have ARM64 manifests. The CVE-specific auth bypass requires
  MySQL 5.1.x-5.5.x compiled with certain glibc versions where memcmp
  returns out-of-range values.
- **What would be needed:** An x86 CI runner with `mysql:5.5`. The test at
  `cve-detection-mysql-version.yaml` uses `mysql:8` as a substitute for
  service detection testing.

## CVE-2015-1427 — Elasticsearch Groovy Sandbox Escape (RCE)
- **Check ID:** `cve.elasticsearch_groovy_rce`
- **Image:** `elasticsearch:1.4.4`
- **Why untestable:** The `elasticsearch:1.4.4` image is x86-only and has been
  deprecated from Docker Hub. It does not run on ARM64 (Apple Silicon). Even on
  x86, the image requires Java 7/8 runtimes that have known TLS issues with
  modern registries.
- **What would be needed:** An x86 CI runner with access to archived Docker
  images, or a custom-built Elasticsearch 1.4.x image.

## CVE-2019-7609 — Kibana Timelion Prototype Pollution (RCE)
- **Check ID:** `cve.kibana_timelion_rce`
- **Image:** `docker.elastic.co/kibana/kibana:6.5.4`
- **Why untestable:** Requires a matching Elasticsearch 6.5.4 instance. The
  combined memory footprint exceeds 2GB. Kibana 6.x takes 2-3 minutes to start
  and frequently OOMs in constrained CI environments.
- **What would be needed:** A dedicated heavy-test runner with 4GB+ RAM and
  5-minute startup tolerance. Two services: ES 6.5.4 + Kibana 6.5.4.

## CVE-2022-0543 — Redis Lua Sandbox Escape (Debian-specific RCE)
- **Check ID:** `cve.redis_lua_sandbox_escape`
- **Image:** Custom Debian Redis build
- **Why untestable:** This CVE only affects Redis packages built by Debian/Ubuntu
  that link against the system Lua library (`liblua5.1`) instead of the bundled
  one. The official `redis:*` Docker images are not affected because they use
  the statically-linked Lua. No public Docker image exists for the vulnerable
  Debian build.
- **What would be needed:** A custom Dockerfile that installs `redis-server` from
  the Debian buster/bullseye apt repository (the vulnerable package versions).

## CVE-2023-28856 — Redis HINCR Auth Bypass
- **Check ID:** `cve.redis_hincr_auth_bypass`
- **Image:** Needs redis < 7.0.11 or < 6.2.12 with AUTH enabled
- **Why untestable:** Requires a specific Redis version with authentication
  enabled AND a client that can send the raw HINCRBYFLOAT command to trigger
  the auth bypass. The exploit is version-specific and the old images are
  increasingly unavailable.
- **What would be needed:** `redis:6.2.11` with `--requirepass` and a raw TCP
  client to send the bypass sequence.

## CVE-2021-22890 — Memcached UDP Amplification
- **Check ID:** `cve.memcached_udp_amplification`
- **Image:** `memcached:1.5` with `-U 11211`
- **Why untestable:** Drydock does not currently support UDP port mapping.
  Docker Compose can map UDP ports (`"11211:11211/udp"`) but the drydock
  test harness only validates TCP readiness probes.
- **What would be needed:** UDP port mapping support in drydock, plus a UDP
  client for the readiness check and exploit proof.

## CVE-2023-7028 — GitLab Account Takeover
- **Check ID:** `cve.gitlab_account_takeover`
- **Image:** `gitlab/gitlab-ce:16.7.0-ce.0`
- **Why untestable:** GitLab CE Docker image is 2.5GB+. Initial startup takes
  5-10 minutes as it runs database migrations, compiles assets, and starts
  multiple internal services (Puma, Sidekiq, Gitaly, PostgreSQL, Redis).
  Frequently exceeds CI timeouts and memory limits.
- **What would be needed:** A dedicated GitLab CI runner with 8GB+ RAM, 10GB
  disk, and 15-minute timeout. Pre-seeded database to skip migrations.

## CVE-2021-22214 — GitLab CI Lint SSRF
- **Check ID:** `cve.gitlab_ci_lint_ssrf`
- **Image:** `gitlab/gitlab-ce:13.10.0-ce.0`
- **Why untestable:** Same constraints as CVE-2023-7028 above. GitLab images
  are 2GB+ and require extended startup time with heavy resource usage.
- **What would be needed:** Same as CVE-2023-7028 — dedicated heavy runner.

## CVE-2020-11978 — Airflow Example DAG RCE
- **Check ID:** `cve.airflow_example_dag_rce`
- **Image:** `apache/airflow:1.10.10`
- **Why untestable:** Airflow 1.10.x uses Python 3.6/3.7 and has incompatible
  dependencies with modern base images. The image is deprecated and frequently
  fails to start due to missing or broken pip packages. The exploit requires
  the example DAGs to be loaded AND the scheduler to be running.
- **What would be needed:** A pinned Airflow 1.10.10 image with pre-installed
  dependencies, example DAGs enabled, and both webserver + scheduler running.
