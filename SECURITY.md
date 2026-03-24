# Security Policy

## Scope

This policy covers security vulnerabilities in the Beacon codebase itself — the `beacon` CLI, the `beacond` server daemon, and all packages under `internal/`.

It does **not** cover:

- Vulnerabilities in third-party tools that Beacon invokes as subprocesses (nuclei, testssl.sh, subfinder, etc.). Report those to the respective upstream projects.
- Findings produced by Beacon when scanning a target. Those are security issues in the target system, not in Beacon.
- Intentional behaviour: deep-mode scanners send active probes by design; this is not a vulnerability in Beacon.

## Supported Versions

Security fixes are applied to the latest release only. We do not backport patches to older versions. If you are running an older release, the remediation is to upgrade.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities via **[GitHub Security Advisories](https://github.com/stormbane/beacon/security/advisories/new)** (private disclosure) or by email to **security@stormbane.com**.

Include in your report:

1. **Description** — what the vulnerability is and what an attacker could do with it.
2. **Affected component** — the package, file, or feature involved.
3. **Steps to reproduce** — a minimal reproduction case. If a proof-of-concept exploit exists, include it.
4. **Impact assessment** — your estimate of severity and the conditions under which the vulnerability is exploitable.
5. **Your contact details** — so we can follow up with questions and notify you when a fix ships.

Encrypted reports are welcome. Our PGP key is published at `https://stormbane.com/.well-known/security.txt`.

## What to Expect

| Timeframe | What happens |
|-----------|-------------|
| 48 hours | Initial acknowledgement of your report |
| 7 days | Triage assessment: confirmed, declined, or needs more information |
| 30 days | Target for a fix to be released for critical and high severity issues |
| 90 days | Target for medium and low severity issues |

We follow coordinated disclosure. We ask that you:

- Give us reasonable time to investigate and release a fix before publishing details publicly.
- Not access, modify, or delete data belonging to other users during research.
- Limit testing to systems you own or have explicit written permission to test — the same restriction Beacon imposes on its own `--deep` mode.

We will:

- Confirm receipt within 48 hours.
- Keep you informed of progress throughout the remediation process.
- Credit you in the release notes and GitHub security advisory (unless you prefer to remain anonymous).
- Not pursue legal action against researchers acting in good faith under this policy.

## Security-Sensitive Areas

The following areas of the codebase are particularly security-sensitive:

**beacond API authentication (`internal/api/middleware.go`)**
The bearer token check is the only authentication mechanism for the remote server API. A bypass here grants unauthenticated access to scan submission and result retrieval.

**Deep mode permission gate (`cmd/beacon/main.go`)**
The `--permission-confirmed` requirement is a legal safeguard. Any code path that allows deep-mode probes to run without this confirmation is a serious issue.

**Scan input handling (`cmd/beacon/main.go`, scanner packages)**
The `domain` input is passed to external subprocess invocations (nuclei, subfinder, testssl.sh). Command injection via a maliciously crafted domain name is a potential vulnerability class across multiple scanners.

**Report rendering (`internal/report/`)**
The HTML report renderer produces output that is opened in browsers. XSS via unescaped finding content (titles, descriptions, evidence values) in the HTML renderer is in scope.

**SQLite store (`internal/store/sqlite/`)**
Finding data gathered from external sources is stored and later retrieved for report rendering. SQL injection or store corruption via crafted scanner output is in scope.

**AI prompt construction (`internal/enrichment/`)**
Prompts sent to the Claude API include finding content gathered from target systems. Prompt injection that causes Claude to emit harmful content, exfiltrate secrets, or circumvent safeguards is in scope.

**Playbook YAML parsing (`internal/playbook/`)**
Playbook files are compiled into the binary at build time. If a future version supports user-supplied playbooks loaded from disk, YAML injection and path traversal would become in scope.

## Severity Ratings

We use the following severity levels, broadly aligned with CVSS v3:

| Severity | Examples |
|----------|---------|
| Critical | Unauthenticated RCE on beacond; authentication bypass on the API server; OS command injection via domain input |
| High | Authenticated RCE; persistent XSS in the HTML report; SQLite injection leading to data exfiltration or local file read |
| Medium | Information disclosure via error messages; denial of service; SSRF in report content fetching |
| Low | Non-exploitable logic errors; minor information leakage in logs; missing security hardening |

## Out of Scope

- Vulnerabilities requiring physical access to the machine running Beacon.
- Social engineering attacks against Stormbane Security personnel.
- Vulnerabilities in upstream dependencies where no exploit path exists in Beacon's specific usage.
- Issues that require the attacker to already have write access to `~/.beacon/config.yaml`, the SQLite database, or the user's home directory — at that point of compromise, the attacker already has equivalent access to the host user.
- Missing HTTP security headers on the `stormbane.com` website (report those to web@stormbane.com instead).
