# Contributing to Beacon

Thank you for your interest in contributing. This guide covers the mechanics of building and testing Beacon, plus the conventions for the two most common contribution types: adding a scanner and adding a playbook.

## Table of Contents

- [Development Setup](#development-setup)
- [Build and Test](#build-and-test)
- [Code Style and Linting](#code-style-and-linting)
- [Adding a Scanner](#adding-a-scanner)
- [Adding a Playbook](#adding-a-playbook)
- [Writing Tests](#writing-tests)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Security Issues](#reporting-security-issues)

---

## Development Setup

**Prerequisites:**

- Go 1.25 or later
- `golangci-lint` for linting
- External scan tools (optional for most unit tests, required for integration testing): `nuclei`, `subfinder`, `testssl.sh`

```sh
# Clone the repository
git clone https://github.com/stormbane/beacon.git
cd beacon

# Install the CLI from source
go install ./cmd/beacon

# Install external scan tools
beacon install

# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

---

## Build and Test

```sh
# Build the beacon binary to ./dist/beacon
make build

# Install beacon to $GOPATH/bin
make install

# Run all tests with the race detector
make test

# Lint
make lint

# Quick smoke test — surface scan against example.com
make smoke
```

Individual test commands:

```sh
# Run tests for a single package
go test ./internal/scanner/tls/... -v -race

# Run tests matching a pattern
go test ./... -run TestEmailSPF -v

# Run with verbose output and a longer timeout (useful for integration tests)
go test ./... -race -timeout 120s -v
```

---

## Code Style and Linting

- Follow standard Go formatting (`gofmt`). The linter will catch formatting issues.
- Package doc comments are required for every new package. The comment should explain what the package detects, what network requests it makes (if any), and whether it is safe in surface mode.
- Error messages should be lowercase and not end with punctuation (Go convention).
- Do not use `log.Fatal`, `os.Exit`, or `panic` inside package code — only in `main`. Return errors instead.
- Surface-mode scanner code must not import packages or use patterns that could result in active payloads. If in doubt, add a `scanType == module.ScanDeep` guard.
- Keep external HTTP client timeouts short (3–10 seconds for most checks) to prevent scanners from stalling the whole scan.

---

## Adding a Scanner

A scanner is a Go package in `internal/scanner/<name>/scanner.go` that implements `scanner.Scanner`.

### 1. Create the package

```
internal/scanner/mycheck/
  scanner.go
  scanner_test.go
```

**`scanner.go` skeleton:**

```go
// Package mycheck detects <what it detects>.
//
// All checks are passive HTTP observations — no payloads, no login attempts.
// Surface-mode safe.
package mycheck

import (
    "context"

    "github.com/stormbane/beacon/internal/finding"
    "github.com/stormbane/beacon/internal/module"
)

const scannerName = "mycheck"

type Scanner struct{}

func New() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return scannerName }

func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
    var findings []finding.Finding

    // Surface checks (passive) go here unconditionally.

    if scanType == module.ScanDeep {
        // Active probes go here — only reached with --deep --permission-confirmed.
    }

    return findings, nil
}
```

### 2. Add CheckID constants

Every distinct finding type needs a stable `CheckID` constant. Add it to `internal/finding/normalize.go`:

```go
const (
    // ... existing constants ...
    CheckMyCheckNoFoo finding.CheckID = "mycheck-no-foo"
    CheckMyCheckBarExposed finding.CheckID = "mycheck-bar-exposed"
)
```

Use the format `<scanner-name>-<finding-description>`, lowercase, hyphen-separated.

### 3. Construct findings correctly

Use the `finding.Finding` struct. Always set `CheckID`, `Title`, `Description`, `Severity`, `Asset`, and `Scanner`. The `Evidence` map should contain all data that makes the finding reproducible and actionable.

```go
findings = append(findings, finding.Finding{
    CheckID:     CheckMyCheckBarExposed,
    Title:       "Bar endpoint publicly accessible",
    Description: "The /bar endpoint responds without authentication and exposes...",
    Severity:    finding.SeverityHigh,
    Asset:       asset,
    Scanner:     scannerName,
    Evidence: map[string]any{
        "url":         barURL,
        "status_code": resp.StatusCode,
        "response":    excerpt,
    },
})
```

### 4. Register the scanner in the surface module

Open `internal/modules/surface/module.go` and add your scanner to the `scanners` map that is constructed in `New()`:

```go
import "github.com/stormbane/beacon/internal/scanner/mycheck"

// inside New(), in the scanners map:
scanners["mycheck"] = mycheck.New()
```

### 5. Add the scanner to a playbook

If the scanner is universally applicable (runs on every asset), add it to the `surface.scanners` or `deep.scanners` list in `internal/playbook/playbooks/baseline.yaml`.

If it is technology-specific, add it to the relevant technology playbook, or create a new playbook (see [Adding a Playbook](#adding-a-playbook)).

### 6. Write tests

See [Writing Tests](#writing-tests). Aim for at least one test per distinct finding type.

### Surface vs. deep: the key rule

Any code that runs when `scanType != module.ScanDeep` must produce no side effects on the target system beyond what a passive browser visit would produce. This means:

- Read-only HTTP GET requests to publicly accessible URLs — acceptable.
- POST requests, login attempts, credential guessing, or payload injection — **deep mode only**.
- Sending more than ~5 requests to a single URL in a short window — use a delay and consider whether this is appropriate for surface mode.

If you are unsure whether a check is surface-safe, ask in your PR and we will review together.

---

## Adding a Playbook

Playbooks are YAML files in `internal/playbook/playbooks/`. They are compiled into the binary via `//go:embed`. No code changes are required to add a playbook — only a new YAML file.

### Playbook file structure

```yaml
name: my-technology          # must match the filename without .yaml
description: >
  What this technology is and why it is security-relevant.
  Include common vulnerability classes and attack patterns.

match:
  any:                       # OR logic — any condition matching activates the playbook
    - body_contains: "my-tech"
    - header_value:
        name: "x-powered-by"
        contains: "MyTech"
    - path_responds: "/my-tech/status"
  # Use "all:" for AND logic if multiple conditions must hold simultaneously.
  # Use "always: true" only for the baseline playbook.

surface:
  scanners:
    - my-scanner             # scanner Name() values registered in the surface module
  nuclei_tags:
    - my-technology          # Nuclei template tags to run against matching assets

deep:
  scanners:
    - dirbust                # always include dirbust in deep if you have a dictionary
  nuclei_tags:
    - my-technology
    - cves
  dictionary:
    # Technology-specific paths to probe in deep/dirbust mode.
    # Do not duplicate paths that are already in baseline.yaml.
    - /my-tech/admin
    - /my-tech/config
    - /my-tech/debug

discovery:
  # Optional: additional subdomain patterns to probe when this technology is detected.
  - type: probe_subdomains
    patterns:
      - "mytech.{domain}"
      - "app.{domain}"
```

### Playbook conventions

**Match conditions should be specific.** A match that fires on a generic string like `"admin"` in the body will activate the playbook on thousands of unrelated assets. Use the most specific signal available for the technology — ideally a unique header, a distinctive body string, or a technology-specific path.

**Do not duplicate baseline paths.** The `baseline.yaml` dictionary already includes universal paths like `/.env`, `/.git/config`, `/admin`, `/api/v1/`, etc. Only add paths that are specific to your technology.

**Nuclei tags must exist.** Verify that the Nuclei template tags you list actually exist in the Nuclei template library before adding them. Running `nuclei -list-templates -tags <tag>` will confirm.

**Test against a real instance.** Before submitting, verify that:
1. The match conditions correctly identify the technology on a real or Docker-based instance.
2. The Nuclei tags produce relevant findings (or at minimum do not error).
3. The dictionary paths return meaningful responses on a real instance.

### Naming convention

Use lowercase, hyphens for spaces, no version numbers in the filename. For vendor-specific variants, use `<vendor>_<product>.yaml` (underscores separate vendor from product, matching Go package naming). For example: `cisco_asa.yaml`, `jenkins_behind_proxy.yaml`.

---

## Writing Tests

### Unit tests for scanners

Scanner tests should be self-contained and not require network access. Use `httptest.NewServer` to serve canned responses:

```go
func TestMyCheckBarExposed(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/bar" {
            w.WriteHeader(200)
            fmt.Fprintln(w, `{"status":"ok","internal_data":"..."}`)
            return
        }
        w.WriteHeader(404)
    }))
    defer srv.Close()

    s := mycheck.New()
    host := strings.TrimPrefix(srv.URL, "http://")
    findings, err := s.Run(context.Background(), host, module.ScanSurface)

    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(findings) == 0 {
        t.Fatal("expected at least one finding, got none")
    }
    got := findings[0]
    if got.CheckID != mycheck.CheckMyCheckBarExposed {
        t.Errorf("CheckID = %q; want %q", got.CheckID, mycheck.CheckMyCheckBarExposed)
    }
    if got.Severity != finding.SeverityHigh {
        t.Errorf("Severity = %v; want High", got.Severity)
    }
}
```

**Rules for scanner tests:**

- Tests must not make real outbound network requests. All HTTP calls must go to `httptest.NewServer`.
- Test both the detection case (finding produced) and the clean case (no finding when the vulnerability is absent).
- Test edge cases: empty responses, unexpected status codes, malformed data.
- The race detector (`-race`) must not report any races. Use goroutine-safe patterns throughout.

### Playbook tests

Playbook match logic is tested in `internal/playbook/match_test.go`. When adding a new playbook with non-trivial match conditions, add a table-driven test case:

```go
{
    name: "my-technology detected via header",
    evidence: playbook.Evidence{
        Headers: map[string]string{"x-powered-by": "MyTech/2.1"},
    },
    playbook: "my-technology",
    want:     true,
},
{
    name: "my-technology not detected on unrelated asset",
    evidence: playbook.Evidence{
        Headers: map[string]string{"x-powered-by": "nginx"},
    },
    playbook: "my-technology",
    want:     false,
},
```

### Test requirements for PRs

- Every new scanner must have tests that achieve meaningful branch coverage of the main detection logic.
- `go test ./... -race` must pass with no failures and no race conditions.
- Tests must complete within the default 60-second timeout (`make test`).
- Do not add tests that depend on external network access, live API keys, or specific files on the developer's machine.

---

## Submitting a Pull Request

1. Fork the repository and create a feature branch from `main`.
2. Make your changes following the conventions above.
3. Run `make test` and `make lint` — both must pass cleanly.
4. Fill out the pull request template completely. Pay particular attention to the scanner and playbook checklists.
5. Keep PRs focused: one scanner or one playbook per PR is easiest to review. Refactors and scanner additions should generally be separate PRs.
6. If your PR involves a new external API or binary dependency, explain in the PR description why it is warranted and what the fallback behaviour is when it is absent.

We aim to review PRs within one week. Complex changes may take longer. If you have not heard back after two weeks, comment on the PR to request a review.

---

## Reporting Security Issues

If you discover a security vulnerability in Beacon itself (not in a target you scanned), please follow the [responsible disclosure process](SECURITY.md) rather than opening a public issue. See `SECURITY.md` for details.
