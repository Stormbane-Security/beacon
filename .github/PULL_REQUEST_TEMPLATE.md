## Summary

<!-- One paragraph describing what this PR does and why. -->

## Type of change

- [ ] Bug fix — corrects incorrect behaviour without changing the public interface
- [ ] New scanner — adds a new `internal/scanner/<name>/scanner.go`
- [ ] New playbook — adds a new `internal/playbook/playbooks/<name>.yaml`
- [ ] Scanner enhancement — extends an existing scanner's detection logic
- [ ] Playbook enhancement — improves match conditions, adds paths, or extends nuclei tags
- [ ] Output / report change — modifies text, markdown, HTML, or JSON rendering
- [ ] Infrastructure / CI — Makefile, Dockerfile, GitHub Actions, deploy config
- [ ] Refactor — internal restructuring without behaviour change
- [ ] Documentation

## Motivation and context

<!-- Why is this change needed? Link related issues with "Closes #NNN" if applicable. -->

## How it works

<!-- Brief technical explanation of the approach. For new scanners: what requests are sent,
     what responses are inspected, what findings are emitted. -->

---

## Checklist

### All changes

- [ ] `go build ./...` succeeds
- [ ] `go test ./... -race` passes
- [ ] `golangci-lint run ./...` passes with no new warnings
- [ ] Commit messages are descriptive

### New or modified scanner

- [ ] The scanner implements `scanner.Scanner` (has `Name()` and `Run(ctx, asset, scanType)`)
- [ ] `Name()` returns a stable, lowercase, hyphen-separated identifier (e.g. `"rate-limit"`)
- [ ] New `CheckID` constants are added to `internal/finding/checkids.go` for each new finding type
- [ ] `ProofCommand` is set on every new `Finding` — every finding must include a copy-paste shell command that reproduces it
- [ ] The scanner is registered in `internal/modules/surface/module.go` (or the appropriate module)
- [ ] The scanner is added to the baseline playbook or an appropriate technology playbook
- [ ] At least one test covers the main detection logic against a mock HTTP server (`httptest.NewServer`)
- [ ] No rubber-stamp tests — tests must verify actual scanner behaviour (given server response X, scanner emits finding Y), not just that the code compiles or that `Run()` returns without error on a 404
- [ ] Surface-mode checks do not send payloads, attempt authentication, or modify server state
- [ ] Deep-mode checks are gated on `scanType == module.ScanDeep`
- [ ] The scanner's package doc comment explains what is checked, what requests are sent, and whether it is surface-safe
- [ ] `README.md` scanner table is updated

### New or modified playbook

- [ ] The playbook file is named `<technology-slug>.yaml` and placed in `internal/playbook/playbooks/`
- [ ] `name:` matches the filename (without `.yaml`)
- [ ] `description:` explains the technology and its security risk profile
- [ ] Match conditions are specific enough to avoid false positives on unrelated assets
- [ ] `surface.nuclei_tags` lists only tags that are relevant to this technology
- [ ] `deep.dictionary` paths are specific to this technology and not already in `baseline.yaml`
- [ ] If adding discovery steps, patterns use `{domain}` substitution correctly
- [ ] The playbook is tested against a real or simulated instance of the technology
- [ ] `README.md` playbook list is updated if this is a new playbook

### AI enrichment / analyze changes

- [ ] Prompt changes are reviewed for prompt injection risk
- [ ] Response parsing handles malformed or empty Claude output gracefully
- [ ] No API keys or secrets appear in test fixtures or prompt templates

### Breaking changes

- [ ] If this changes a `Finding` field, `CheckID` constant, or store schema: migration is provided and noted in the PR description
- [ ] If this changes CLI flags or environment variable names: the README is updated and a deprecation notice is added if removing old names

## Testing notes

<!-- Describe how you tested this change. Include the domain(s) or mock server used,
     the scan mode (surface/deep), and what output confirmed correct behaviour. -->

## Screenshots or sample output

<!-- If this changes report output or the TUI, paste a before/after sample or screenshot. -->
