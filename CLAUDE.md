# Beacon — Claude Code Instructions

## Commit Conventions

**Always create commits when explicitly asked.** Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <short summary>

<body — what changed and why, not what the diff says>

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
```

### Types
| Type | When to use |
|------|-------------|
| `feat` | New scanner, new check ID, new TUI feature, new CLI flag |
| `fix` | Bug fix in scanner logic, false positive/negative correction |
| `perf` | Parallelization, caching, reduced HTTP requests |
| `test` | New or updated tests |
| `refactor` | Code restructuring without behavior change |
| `docs` | README, CONTRIBUTING, code comments |
| `chore` | Deps, build config, CI |
| `security` | Security hardening of beacon itself (not scanner findings) |

### Scopes (use the scanner or package name)
`scanner/cors`, `scanner/jwt`, `tui`, `cli`, `playbook`, `config`, `auth`, `module`, `report`

### Examples
```
feat(scanner/cors): add preflight OPTIONS check for CORS misconfig

Simple GET-based origin probes miss CORS issues on endpoints that only
allow credentialed preflight requests. Add OPTIONS probe with
Access-Control-Request-Method and Access-Control-Request-Headers to
catch the more dangerous pattern.

fix(scanner/apiversions): parallelize probes to reduce scan time

20 sequential HTTP requests took 20× network RTT. Now runs 10 concurrent
goroutines, reducing wall time from ~16s to ~2s on typical targets.

feat(tui): add topology detail pane with full asset evidence

Pressing Enter on a topology host now opens a scrollable detail view
showing all paths, auth system, TLS, DNS, open ports, and web3 signals.
```

### When to commit
- After completing a discrete unit of work (one scanner fix, one feature, one set of tests)
- Before switching to a different area of the codebase
- When the build and relevant tests pass
- **Never** commit broken builds or failing tests

---

## Release Policy

Beacon uses **semantic versioning** (`MAJOR.MINOR.PATCH`):

| Version bump | When |
|---|---|
| `PATCH` (0.x.Y) | Bug fixes, false positive/negative corrections, playbook fixes, test additions |
| `MINOR` (0.X.0) | New scanners, new TUI features, new CLI flags, new scan modes, AuthConfig |
| `MAJOR` (X.0.0) | Breaking changes to CLI flags, config schema, or finding output format that require user migration |

### When to cut a release
Suggest a release when any of these are true:
- 5+ scanner fixes or improvements have accumulated since last release
- A new scan mode or major feature is complete (`ScanAuthorized`, authenticated scanning, etc.)
- A critical false positive fix that users may be seeing in prod
- README/docs are up to date and `go test ./...` is fully green

### Release checklist
1. `go test ./...` — all pass
2. `go build ./...` — clean
3. `go vet ./...` — clean
4. Update version constant if one exists (check `cmd/beacon/main.go` for `version =`)
5. Tag: `git tag -s v0.X.Y -m "release: v0.X.Y"`
6. Push tag: `git push origin v0.X.Y`

---

## Code Standards

- All scanners must have behavior-driven tests: given server response X → scanner emits/doesn't emit finding Y
- No rubber-stamp tests that just verify the scanner compiles
- `ScanSurface` = safe for unsolicited scans (no active payloads)
- `ScanDeep` = active probing (requires `--permission-confirmed`)
- `ScanAuthorized` = exploitation-class (requires `--authorized` + interactive acknowledgment)
- Every finding must have `ProofCommand` set
- New check IDs go in `internal/finding/checkids.go`
- New scanners must be registered in `internal/modules/surface/module.go` and added to at least one playbook

## Project Context

Beacon is an attack surface scanner. Primary users are security researchers and pentesters scanning their own infrastructure or systems they have written authorization to test. The tool is safe-by-default: surface mode does only passive observation that any internet user could do.
